# Requirements Document

## Introduction

This specification defines the valid detection benchmark used to determine whether a detector works on application repositories it has not seen. It replaces the 2026-10-12 pilot as admission evidence because that pilot reused repositories protected by the permanent reservation policy. The historical pilot remains preserved as withdrawn evidence, while a separately sourced population establishes a new baseline.

The replacement is a general Python and JavaScript/TypeScript benchmark rather than an access-control-only population. It measures multiple vulnerability families and reports quality for each declared vulnerability-family and ecosystem scope. A whole-population result describes coverage only; it cannot substitute for a scoped quality denominator.

## Boundary Context

- **In scope**: population sourcing and review, fix-derived labels, ordinary-change selection, permanent reservation, development/admission separation, label isolation, lifecycle and custody, reproducible freezing, push-path replay, scoped denominators, standard metrics, failure visibility, and benchmark reporting.
- **Out of scope**: adding or tuning detection logic, facts, prompts, thresholds, or judges; wiring detector arms into the pre-push product; enabling rollout; reactivating a parked detector arm; and operating execution-plane infrastructure.
- **Adjacent expectations**: detector arms provide immutable declared identities and claimed scopes; the shared detection contracts validate admission and scoring; the proof workflow supplies demonstrated-exploit evidence; product specifications decide rollout from eligible scoped results.

## Requirements

### Requirement 1: General Multi-Family Population

**Objective:** As a maintainer, I want one general benchmark spanning the initial supported languages and multiple vulnerability families, so that shared detection improvements and class-specific arms can be evaluated without building a new population for every arm.

#### Acceptance Criteria

1. The Valid Detection Benchmark shall include accepted application cases from both Python and JavaScript/TypeScript ecosystems.
2. The Valid Detection Benchmark shall include accepted positives from at least two distinct vulnerability families overall.
3. When the full replacement population is accepted, the Valid Detection Benchmark shall contain at least 40 accepted positives overall.
4. If a frozen population contains fewer than 40 accepted positives, the Valid Detection Benchmark shall classify it as a development pilot or insufficient population and shall not use it as the full replacement admission baseline.
5. When the benchmark records an ecosystem, the Valid Detection Benchmark shall use one reviewed canonical ecosystem identity for that repository.
6. If a repository's ecosystem classification remains unresolved, the Valid Detection Benchmark shall record insufficient scope evidence for that repository.
7. If a vulnerability-family and ecosystem scope lacks enough eligible cases for its pre-registered gate, the Valid Detection Benchmark shall report that scope as insufficient and shall not infer support from the whole-population count.
8. When concrete frameworks or repositories are cited, the Valid Detection Benchmark shall treat them as coverage evidence rather than as detector implementation requirements.

### Requirement 2: Fix-Derived Positive Ground Truth

**Objective:** As a benchmark reviewer, I want each positive anchored to a security fix and reachable application behavior, so that recall is measured against reviewed vulnerability locations rather than inferred history.

#### Acceptance Criteria

1. When a positive candidate is sourced, the Valid Detection Benchmark shall derive its vulnerable location from the file and function changed by the security fix at the vulnerable parent revision.
2. The Valid Detection Benchmark shall not derive a positive location from a blame walk-back or another SZZ-style introducing-commit estimate.
3. When a positive candidate is reviewed, the Valid Detection Benchmark shall require a human reviewer whose recorded identity differs from the producer's identity, satisfies the pre-registered review policy, and includes a conflict disclosure to confirm that the vulnerable revision contains the defect, the fixed revision addresses it, and an entry point inside the repository can reach it.
4. If any required ground-truth or reachability judgment is rejected or missing, the Valid Detection Benchmark shall exclude the candidate and record a reason.
5. Where model-assisted adjudication is used during curation, the Valid Detection Benchmark shall record it as non-authoritative review assistance and shall not treat model agreement as a label.
6. When one fix has independently verified labels in multiple scopes, the Valid Detection Benchmark shall count the push once in whole-population coverage and once in each verified scoped denominator without granting credit to an unverified family or ecosystem.

### Requirement 3: Representative Ordinary Changes

**Objective:** As a developer, I want false alarms measured on ordinary changes from the same application environments, so that the reported interruption rate reflects the push experience.

#### Acceptance Criteria

1. When an accepted positive repository contributes negatives, the Valid Detection Benchmark shall draw ordinary non-security changes from that repository's first-parent history and shall exclude the security fix.
2. The Valid Detection Benchmark shall include at least 20 eligible ordinary pushes per accepted positive in each frozen population.
3. When calculating a scoped false-alarm denominator, the Valid Detection Benchmark shall include each eligible ordinary push from the matching ecosystem once for each vulnerability family claimed by the evaluated arm in that ecosystem.
4. The Valid Detection Benchmark shall not pool an ordinary push from one ecosystem into another ecosystem's denominator.
5. If an ordinary change is verified to contain a relevant security defect before freeze, the Valid Detection Benchmark shall exclude it from the population and record the reason.
6. If an ordinary change is verified to contain a relevant security defect after freeze, the Valid Detection Benchmark shall retire the affected baseline rather than silently rewriting its recorded result.

### Requirement 4: Permanent Reservation and Historical Withdrawal

**Objective:** As a benchmark custodian, I want prior repository use and withdrawn populations handled explicitly, so that development knowledge cannot leak into new admission evidence.

#### Acceptance Criteria

1. The Valid Detection Benchmark shall exclude every repository identity present in the authoritative permanent-reservation census.
2. When repository aliases, former names, redirects, or fork relationships resolve to a reserved identity, the Valid Detection Benchmark shall treat the candidate as reserved.
3. When repository code, labels, or metadata influence population selection, detector development, training, tuning, mining, fact promotion, prompt selection, or threshold selection, the Valid Detection Benchmark shall add that repository identity to the permanent-reservation census.
4. If a repository was only enumerated and none of its code, labels, or metadata influenced a decision, the Valid Detection Benchmark shall not classify it as used unless another reservation source includes it.
5. The Valid Detection Benchmark shall classify the 2026-10-12 pilot as withdrawn and non-admissible and shall not present its results as current qualification evidence.
6. When the historical pilot is withdrawn, the Valid Detection Benchmark shall preserve its bytes and digests.
7. When the historical pilot is withdrawn, the Valid Detection Benchmark shall add a reviewed lifecycle record containing the withdrawal reason and replacement relationship.
8. If historical identity-bearing material remains accessible for audit, the Valid Detection Benchmark shall authorize it only by exact path and digest and shall not create a blanket reservation-guard exclusion.
9. When the replacement population is frozen, the Valid Detection Benchmark shall use new population and freeze identities and shall not replace or rewrite the historical pilot in place.
10. When a replacement population is about to be accepted, the Valid Detection Benchmark shall pass the permanent-reservation guard while permitting only reviewed exact-path-and-digest historical authorizations and without weakening reservation semantics.

### Requirement 5: Development and Admission Separation

**Objective:** As a release decision maker, I want detector development separated from untouched admission, so that measured qualification is not influenced by the labels it evaluates.

#### Acceptance Criteria

1. The Valid Detection Benchmark shall maintain disjoint development and admission populations.
2. When a population or slice is inspected to diagnose, tune, select, or promote detector behavior, the Valid Detection Benchmark shall classify it as development or spent and shall not use it for admission.
3. When admission is prepared and before labels are opened, the Valid Detection Benchmark shall freeze a label-blind manifest containing only scope census information and digests.
4. When a label-blind manifest is reviewed, the Valid Detection Benchmark shall require a reviewer whose recorded identity differs from the producer's identity, satisfies the pre-registered review policy, and includes a conflict disclosure.
5. When admission is prepared and before labels are opened, the Valid Detection Benchmark shall bind the population, analyzer, configuration, fact set, judgment vocabulary, outcome mapping, denominator policy, thresholds, and claimed scopes to immutable identities.
6. If admission labels influence facts, strategies, matchers, prompts, examples, thresholds, judges, decision mappings, or promotions, the Valid Detection Benchmark shall mark the population spent and refuse an admission result from it.
7. When admission labels are released, the Valid Detection Benchmark shall durably record the spent transition before exposing any label bytes.
8. When a post-spend case is released for scoring, the Valid Detection Benchmark shall bind the case to its scope, role, pair identity, result, evidence, change inputs, and reviewed input manifest.
9. When a post-spend case release is reviewed, the Valid Detection Benchmark shall require a reviewer whose recorded identity differs from the producer's identity, satisfies the pre-registered review policy, and includes a conflict disclosure.

### Requirement 6: Scoped Denominators and Feasible Gates

**Objective:** As a detector owner, I want quality evaluated only on the families and ecosystems an arm claims, so that out-of-scope cases neither dilute nor inflate its result.

#### Acceptance Criteria

1. When an arm is registered and before label access, the Valid Detection Benchmark shall require the arm to declare every vulnerability-family and ecosystem scope it claims.
2. When recall or pair correctness is calculated for a scope, the Valid Detection Benchmark shall use only vulnerable and fixed cases independently verified for that exact family and ecosystem.
3. When false alarms and precision are calculated for a scope, the Valid Detection Benchmark shall use only findings and ordinary pushes assigned to that exact family and ecosystem under the pre-registered denominator policy.
4. The Valid Detection Benchmark shall report whole-population coverage separately from scoped quality metrics.
5. Where an overall aggregate is provided, the Valid Detection Benchmark shall identify its constituent scopes, sample counts, and weighting and shall not use that aggregate to authorize a capability or ecosystem claim.
6. When a gate is registered and before label access, the Valid Detection Benchmark shall prove from the label-blind census that every pre-registered threshold is arithmetically reachable for its declared denominator.
7. If a threshold is impossible or a scoped denominator fails its pre-registered minimum size or interval-precision rule, the Valid Detection Benchmark shall refuse to spend the population for that gate and shall report the scope as insufficient.

### Requirement 7: Reproducible Population and Durable Custody

**Objective:** As an operator, I want population state and provenance to survive restart or local-disk loss, so that a long sourcing or admission workflow remains reproducible and auditable.

#### Acceptance Criteria

1. When a population is frozen, the Valid Detection Benchmark shall bind its positive selection, ordinary-change draw, reservation census, review records, exclusion counts, and provenance to content digests.
2. When unchanged source material is frozen again under the same policy, the Valid Detection Benchmark shall produce the same population identity.
3. If an existing frozen identity resolves to different content, the Valid Detection Benchmark shall refuse the write and preserve the prior artifact.
4. The Valid Detection Benchmark shall keep durable population state, custody transitions, provenance, and resumable sourcing state in a versioned durable store rather than relying on local scratch files.
5. If local scratch state is lost or execution restarts, the Valid Detection Benchmark shall resume from durable custody without changing accepted decisions or identities.
6. Where material is publicly distributed, the Valid Detection Benchmark shall include only permissively licensed content; non-permissive or uncertain material shall remain private behind opaque digest-bound references.
7. The Valid Detection Benchmark shall retain durable population, provenance, lifecycle, and custody records in an auditable form.
8. When transient run records are created, the Valid Detection Benchmark shall apply a pre-registered time-bounded retention policy that expires both current and noncurrent versions by their recorded deadlines.

### Requirement 8: Standard Measurement and Failure Visibility

**Objective:** As a reviewer, I want every benchmark result to carry the same complete measurement record, so that a clean result, an unsupported result, and a failed instrument cannot be confused.

#### Acceptance Criteria

1. When a benchmark result is published, the Valid Detection Benchmark shall identify the population and freeze digests, judgment vocabulary, claimed scopes, denominator policy, analyzer and fact identities, and threshold set.
2. When a scoped result is published, the Valid Detection Benchmark shall report recall, false alarms per 100 ordinary pushes, precision, pair correctness, sample counts, and Wilson 95% intervals.
3. When a benchmark result is published, the Valid Detection Benchmark shall report whole-population coverage, completed and deferred work, instrument and model failures, runtime, and every degradation with its reason.
4. When a zero or clean-looking result is about to be interpreted, the Valid Detection Benchmark shall prove nonzero input reads and execution of every stage required by the declared arm.
5. If an input is unreadable, empty, skipped, prematurely terminated, or processed by a failed required stage, the Valid Detection Benchmark shall report an instrument failure or bounded incomplete result and shall not count it as clean.
6. When the population, vocabulary, denominator, claimed scope, analyzer identity, fact identity, threshold set, or outcome mapping changes, the Valid Detection Benchmark shall start a new baseline and shall not describe the new result as a regression trend against an incompatible baseline.

### Requirement 9: Push-Path Arms and Demonstrated Evidence

**Objective:** As a product owner, I want benchmark arms and proof strength reported distinctly, so that experimental assistance is not mistaken for shipped behavior or demonstrated exploitation.

#### Acceptance Criteria

1. When the shipped push path and an experimental detector arm are evaluated, the Valid Detection Benchmark shall report their results separately over the same eligible changes.
2. Where a pre-registered combined arm is evaluated, the Valid Detection Benchmark shall identify its combination rule before label access and shall preserve each contributing arm's result.
3. When an exploit-demonstrated rate is reported, the Valid Detection Benchmark shall require a matching differential proof artifact showing the owned effect on the vulnerable revision and its absence on the fixed revision.
4. If a flagged positive lacks a matching differential proof artifact, the Valid Detection Benchmark shall report it as not demonstrated rather than as a failed exploit or an exploit-verified finding.
5. The Valid Detection Benchmark shall not treat scanner verification, model confidence, or model agreement as demonstrated-exploit evidence.
6. When reporting advisory eligibility, the Valid Detection Benchmark shall scope the result per capability and ecosystem.
7. When reporting a blocking claim, the Valid Detection Benchmark shall require demonstrated proof.

### Requirement 10: Operator Outcomes and Feature Boundary

**Objective:** As an operator, I want benchmark completion and impairment states to be explicit while detector and infrastructure decisions remain with their owning workflows.

#### Acceptance Criteria

1. When a benchmark workflow completes, the Valid Detection Benchmark shall expose its status, counts, digests, scoped GO, NO-GO, or insufficient outcomes, and named failed gates.
2. If a benchmark workflow stalls, times out, exhausts a budget or resource, produces an insufficient result, or encounters an instrument failure, the Valid Detection Benchmark shall expose the impaired state and its reason.
3. The Valid Detection Benchmark shall not include secrets, exploit payloads, private labels, repository contents, or customer content in shared reports or operator notifications.
4. The Valid Detection Benchmark shall not modify detector logic, facts, prompts, judges, thresholds, or product rollout state while constructing or scoring a population.
5. The Valid Detection Benchmark shall not reactivate or requalify the parked access-control arm without a separate maintainer strategy decision.
6. Where an execution plane is used, the Valid Detection Benchmark shall report benchmark process outcomes without assuming ownership of worker, cluster, or network infrastructure health.
